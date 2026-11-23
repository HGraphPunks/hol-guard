use super::*;
use serde_json::json;
fn fixture() -> (Value, WorkerRequest, String) {
    let generation = "c".repeat(64);
    let value = json!({"schema":"hol-gauntlet-native-worker-job.v1","profile":"native-apparatus-v1",
        "source_sha":"a".repeat(40),"job_id":"0123456789abcdef","worker_generation":generation,
        "preparation_sha256":"b".repeat(64),"case":"success"});
    let digest = format!("{:x}", Sha256::digest(value.to_string().as_bytes()));
    let request = WorkerRequest::parse(
        json!({"schema":"hol-gauntlet-worker-request.v1","action":"run",
        "source_sha":"a".repeat(40),"job_id":"0123456789abcdef","deployment_digest":digest})
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    (value, request, generation)
}

#[test]
fn hook_transport_is_a_distinct_closed_version_and_cannot_borrow_product_identity() {
    let (mut value, _, generation) = fixture();
    value["schema"] = json!("hol-gauntlet-native-worker-job.v2");
    value["profile"] = json!("native-hook-transport-v1");
    value.as_object_mut().unwrap().remove("case");
    value["guard"] = json!({"schema":"hol-gauntlet-native-hook-product-pins.v1","source_sha":"a".repeat(40),
        "package_version":"3.57.0","native_sha256":"b".repeat(64),"bwrap_sha256":"c".repeat(64)});
    let parse = |v: &Value| {
        let raw = v.to_string();
        let digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
        let request = WorkerRequest::parse(
            json!({"schema":"hol-gauntlet-worker-request.v1","action":"run",
            "source_sha":"a".repeat(40),"job_id":"0123456789abcdef","deployment_digest":digest})
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        NativeJobSpec::parse(raw.as_bytes(), &digest, &request, &generation)
    };
    let spec = parse(&value).unwrap();
    assert_eq!(spec.profile(), "native-hook-transport-v1");
    assert_eq!(spec.case(), "native-hook-transport");
    assert!(matches!(
        spec.execution,
        NativeJobExecution::HookTransport(_)
    ));
    assert!(!spec.requires_host_pin());
    let mut keyed = value.clone();
    keyed["schema"] = json!("hol-gauntlet-native-worker-job.v8");
    keyed["profile"] = json!("native-host-pinned-readonly-hook-v1");
    let parsed = parse(&keyed).unwrap();
    assert!(parsed.requires_host_pin());
    assert_eq!(parsed.case(), "readonly-utility");
    assert!(matches!(
        parsed.execution,
        NativeJobExecution::HostPinnedReadonlyHook(_)
    ));
    for (field, bad) in [
        ("schema", json!("hol-gauntlet-native-worker-job.v2")),
        ("profile", json!("native-hook-transport-v1")),
        ("sdk", json!({})),
        ("role", json!("success")),
    ] {
        let mut changed = keyed.clone();
        changed[field] = bad;
        assert!(parse(&changed).is_err(), "{field}");
    }
    let mut mcp = value.clone();
    mcp["schema"] = json!("hol-gauntlet-native-worker-job.v4");
    mcp["profile"] = json!("native-mcp-transport-v1");
    let parsed = parse(&mcp).unwrap();
    assert_eq!(parsed.profile(), "native-mcp-transport-v1");
    assert!(matches!(
        parsed.execution,
        NativeJobExecution::McpTransport(_)
    ));
    for (field, bad) in [
        ("schema", json!("hol-gauntlet-native-worker-job.v3")),
        ("profile", json!("native-hook-transport-v1")),
        ("sdk", json!({})),
        ("command", json!("sh")),
    ] {
        let mut changed = mcp.clone();
        changed[field] = bad;
        assert!(parse(&changed).is_err());
    }
    for (pointer, bad) in [
        ("/guard/source_sha", json!("d".repeat(40))),
        ("/guard/bwrap_sha256", json!(true)),
        ("/profile", json!("native-apparatus-v1")),
        ("/schema", json!("hol-gauntlet-native-worker-job.v1")),
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).unwrap() = bad;
        assert!(parse(&changed).is_err(), "{pointer}");
    }
    for key in ["case", "command", "execution_eligible"] {
        let mut changed = value.clone();
        changed[key] = json!("untrusted");
        assert!(parse(&changed).is_err(), "{key}");
    }
}
#[test]
fn sdk_requires_its_own_version_and_both_outside_product_and_dependency_pins() {
    let (mut value, _, generation) = fixture();
    value["schema"] = json!("hol-gauntlet-native-worker-job.v3");
    value["profile"] = json!("native-sdk-transport-v1");
    value.as_object_mut().unwrap().remove("case");
    value["guard"] = json!({"schema":"hol-gauntlet-native-hook-product-pins.v1","source_sha":"a".repeat(40),
        "package_version":"3.57.0","native_sha256":"b".repeat(64),"bwrap_sha256":"c".repeat(64)});
    value["sdk"] = NativeSdkPins {
        sdk_tree_sha256: "d".repeat(64),
        bun_sha256: "e".repeat(64),
        publication_sha256: "f".repeat(64),
    }
    .to_json();
    let parse = |v: &Value| {
        let raw = v.to_string();
        let digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
        let request = WorkerRequest::parse(
            json!({"schema":"hol-gauntlet-worker-request.v1","action":"run",
            "source_sha":"a".repeat(40),"job_id":"0123456789abcdef","deployment_digest":digest})
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        NativeJobSpec::parse(raw.as_bytes(), &digest, &request, &generation)
    };
    let spec = parse(&value).unwrap();
    assert_eq!(spec.profile(), "native-sdk-transport-v1");
    assert!(matches!(
        spec.execution,
        NativeJobExecution::SdkTransport { .. }
    ));
    let mut composed = value.clone();
    composed["schema"] = json!("hol-gauntlet-native-worker-job.v5");
    composed["profile"] = json!("native-sdk-mcp-transport-v1");
    let parsed = parse(&composed).unwrap();
    assert_eq!(parsed.profile(), "native-sdk-mcp-transport-v1");
    assert!(matches!(
        parsed.execution,
        NativeJobExecution::SdkMcpTransport { .. }
    ));
    let mut control = composed.clone();
    control["schema"] = json!("hol-gauntlet-native-worker-job.v6");
    control["profile"] = json!("native-deterministic-control-v1");
    for role in [
        "success",
        "input-binding",
        "injection",
        "boundary",
        "timeout",
        "cancel",
    ] {
        control["role"] = json!(role);
        let parsed = parse(&control).unwrap();
        assert_eq!(parsed.profile(), "native-deterministic-control-v1");
        assert_eq!(parsed.case(), role);
        assert!(matches!(
            parsed.execution,
            NativeJobExecution::DeterministicControl { .. }
        ));
        assert!(!parsed.requires_host_pin());
        let mut pinned = control.clone();
        pinned["schema"] = json!("hol-gauntlet-native-worker-job.v7");
        pinned["profile"] = json!("native-host-pinned-control-v1");
        let keyed = parse(&pinned).unwrap();
        assert!(keyed.requires_host_pin());
        assert_eq!(keyed.profile(), "native-host-pinned-control-v1");
        assert_eq!(keyed.case(), role);
        assert!(matches!(
            keyed.execution,
            NativeJobExecution::HostPinnedControl { .. }
        ));
        pinned["schema"] = json!("hol-gauntlet-native-worker-job.v6");
        assert!(parse(&pinned).is_err());
    }
    for bad in [
        json!("shell"),
        json!(true),
        json!({"role":"success"}),
        json!(null),
    ] {
        control["role"] = bad;
        assert!(parse(&control).is_err());
    }
    control["role"] = json!("input-binding");
    let mut live = composed.clone();
    live["schema"] = json!("hol-gauntlet-native-worker-job.v9");
    live["profile"] = json!("native-host-pinned-live-omp-v1");
    live["live"] = json!({"schema":"hol-gauntlet-native-live-omp-job.v1","cell_id":crate::native_live_spec::FEATURE_AI_BASELINE,"spec_sha256":"1".repeat(64),
        "model":{"schema":"hol-gauntlet-native-live-model-pins.v1","provider_job_id":"2".repeat(16),"budget_digest":"3".repeat(64),"model_id":crate::native_live_model::MODEL,"max_turns":32,"token_limit":100000}});
    let parsed = parse(&live).unwrap();
    assert_eq!(parsed.profile(), "native-host-pinned-live-omp-v1");
    assert_eq!(parsed.case(), "feature-ai-unprotected");
    assert!(parsed.requires_host_pin());
    for (pointer, bad) in [
        ("/schema", json!("hol-gauntlet-native-worker-job.v7")),
        ("/profile", json!("native-host-pinned-control-v1")),
        ("/live/cell_id", json!("input-binding")),
        ("/live/model/model_id", json!("caller-model")),
        ("/guard/source_sha", json!("b".repeat(40))),
    ] {
        let mut changed = live.clone();
        *changed.pointer_mut(pointer).unwrap() = bad;
        assert!(parse(&changed).is_err(), "{pointer}");
    }
    live["role"] = json!("success");
    assert!(parse(&live).is_err());
    control["schema"] = json!("hol-gauntlet-native-worker-job.v5");
    assert!(parse(&control).is_err());
    for (pointer, bad) in [
        ("/schema", json!("hol-gauntlet-native-worker-job.v3")),
        ("/profile", json!("native-sdk-transport-v1")),
        ("/sdk/publication_sha256", json!("bad")),
        ("/guard/source_sha", json!("b".repeat(40))),
    ] {
        let mut changed = composed.clone();
        *changed.pointer_mut(pointer).unwrap() = bad;
        assert!(parse(&changed).is_err(), "{pointer}");
    }
    for key in ["guard", "sdk"] {
        let mut changed = composed.clone();
        changed.as_object_mut().unwrap().remove(key);
        assert!(parse(&changed).is_err());
    }
    for (pointer, bad) in [
        ("/schema", json!("hol-gauntlet-native-worker-job.v2")),
        ("/profile", json!("native-hook-transport-v1")),
        ("/guard/source_sha", json!("b".repeat(40))),
        ("/sdk/publication_sha256", json!("bad")),
        ("/sdk/agent_image_id", json!("other")),
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).unwrap() = bad;
        assert!(parse(&changed).is_err(), "{pointer}");
    }
    for key in ["guard", "sdk"] {
        let mut changed = value.clone();
        changed.as_object_mut().unwrap().remove(key);
        assert!(parse(&changed).is_err());
    }
    value["command"] = json!("sh");
    assert!(parse(&value).is_err());
}
#[test]
fn request_source_job_deployment_and_worker_are_all_external_bindings() {
    let (value, request, generation) = fixture();
    let digest = request.deployment_digest().unwrap();
    let spec =
        NativeJobSpec::parse(value.to_string().as_bytes(), digest, &request, &generation).unwrap();
    assert_eq!(
        spec.preparation_path(),
        PathBuf::from(
            "/var/lib/hol-gauntlet-rust/native-jobs/0123456789abcdef/preparation.v1.json"
        )
    );
    assert!(NativeJobSpec::parse(
        value.to_string().as_bytes(),
        digest,
        &request,
        &"d".repeat(64)
    )
    .is_err());
    for (key, bad) in [
        ("job_id", json!("fedcba9876543210")),
        ("source_sha", json!("e".repeat(40))),
        ("profile", json!("workflow")),
        ("case", json!("sh")),
        ("preparation_sha256", json!(true)),
        ("command", json!("sh")),
        ("execution_eligible", json!(true)),
    ] {
        let mut bad_value = value.clone();
        bad_value[key] = bad;
        let raw = bad_value.to_string();
        let bad_digest = format!("{:x}", Sha256::digest(raw.as_bytes()));
        let bound_request=WorkerRequest::parse(json!({"schema":"hol-gauntlet-worker-request.v1","action":"run",
            "source_sha":request.source_sha(),"job_id":request.job_id(),"deployment_digest":bad_digest}).to_string().as_bytes()).unwrap();
        assert!(
            NativeJobSpec::parse(raw.as_bytes(), &bad_digest, &bound_request, &generation).is_err(),
            "{key}"
        );
    }
}

#[test]
fn valid_preparations_cannot_borrow_another_jobs_workspace_stage_or_slice() {
    let (value, request, generation) = fixture();
    let mut job = NativeJobSpec::parse(
        value.to_string().as_bytes(),
        request.deployment_digest().unwrap(),
        &request,
        &generation,
    )
    .unwrap();
    let root = job.job_root();
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
    let value = json!({"schema":"hol-gauntlet-cell-preparation.v1","stage":root.join("cell"),
        "artifacts":"/opt/hol-gauntlet/generation/artifacts","artifact_manifest_sha256":"a".repeat(64),"initializer_sha256":"b".repeat(64),
        "runtime_prefix":"/opt/hol-gauntlet/generation/prefix","runtime_tree_digest":"c".repeat(64),"image_id":format!("sha256:{}","d".repeat(64)),"podman_sha256":"e".repeat(64),
        "task_mounts":{"schema":"product-cell-task-mounts.v1","workspace":{"source":root.join("workspace"),"destination":"/runtime/home/project","custody_root":root,"device":1,"inode":2,"mode":448},"providers":[]},
        "launch":{"schema":"hol-gauntlet-cell-supervisor.v1","constructor":"/opt/hol-gauntlet/generation/gauntlet-cell-rootfs","constructor_sha256":"f".repeat(64),"wall_seconds":180,"cpu_profile":"single-core-v1","job_slice":"holgauntletrust0123456789abcdef.slice","host_helpers":helpers}});
    let raw = value.to_string();
    job.preparation_sha256 = format!("{:x}", Sha256::digest(raw.as_bytes()));
    assert!(job.preparation(raw.as_bytes()).is_ok());
    let mut readonly = value.clone();
    readonly["schema"] = json!("hol-gauntlet-cell-preparation.v2");
    readonly["control_profile"] = json!("python-readonly.v1");
    readonly["launch"]["schema"] = json!("hol-gauntlet-cell-supervisor.v5");
    readonly["launch"]["process_events"] = json!("outside-root-ptrace.v1");
    readonly["launch"]["native_stdio"] = json!("outside-root-native-pipes.v1");
    readonly["launch"]["native_runtime_sha256"] = json!("b".repeat(64));
    readonly["launch"]["image_interpreter_sha256"] = json!("a".repeat(64));
    readonly["launch"]["outside_observer_sha256"] = json!("c".repeat(64));
    let raw = readonly.to_string();
    job.preparation_sha256 = format!("{:x}", Sha256::digest(raw.as_bytes()));
    assert!(job.preparation(raw.as_bytes()).is_err());
    job.execution = NativeJobExecution::HookTransport(NativeGuardPins {
        source_sha: "a".repeat(40),
        package_version: "3.59.0".into(),
        native_sha256: "b".repeat(64),
        bwrap_sha256: "c".repeat(64),
    });
    assert!(job.preparation(raw.as_bytes()).is_ok());
    let NativeJobExecution::HookTransport(pins) = &job.execution else {
        panic!("hook fixture required")
    };
    job.execution = NativeJobExecution::HostPinnedReadonlyHook(pins.clone());
    assert!(job.preparation(raw.as_bytes()).is_ok());
    let mut namespace = readonly.clone();
    namespace["launch"]["schema"] = json!("hol-gauntlet-cell-supervisor.v6");
    let raw = namespace.to_string();
    job.preparation_sha256 = format!("{:x}", Sha256::digest(raw.as_bytes()));
    assert!(job.preparation(raw.as_bytes()).is_err());
    namespace["launch"]["host_helpers"]["/usr/bin/nsenter"] = json!("1".repeat(64));
    let raw = namespace.to_string();
    job.preparation_sha256 = format!("{:x}", Sha256::digest(raw.as_bytes()));
    assert!(job.preparation(raw.as_bytes()).is_ok());
    namespace["launch"]["host_helpers"]["/usr/bin/nsenter"] = json!(false);
    let raw = namespace.to_string();
    job.preparation_sha256 = format!("{:x}", Sha256::digest(raw.as_bytes()));
    assert!(job.preparation(raw.as_bytes()).is_err());
    let legacy = value.to_string();
    job.preparation_sha256 = format!("{:x}", Sha256::digest(legacy.as_bytes()));
    assert!(job.preparation(legacy.as_bytes()).is_err());
    for (pointer, bad) in [
        (
            "/stage",
            json!("/var/lib/hol-gauntlet-rust/native-jobs/fedcba9876543210/cell"),
        ),
        (
            "/launch/job_slice",
            json!("holgauntletrustfedcba9876543210.slice"),
        ),
    ] {
        let mut changed = readonly.clone();
        *changed.pointer_mut(pointer).unwrap() = bad;
        let raw = changed.to_string();
        job.preparation_sha256 = format!("{:x}", Sha256::digest(raw.as_bytes()));
        assert!(job.preparation(raw.as_bytes()).is_err(), "{pointer}");
    }
    let mut changed = readonly.clone();
    changed["task_mounts"]["workspace"]["source"] =
        json!("/var/lib/hol-gauntlet-rust/native-jobs/fedcba9876543210/workspace");
    changed["task_mounts"]["workspace"]["custody_root"] =
        json!("/var/lib/hol-gauntlet-rust/native-jobs/fedcba9876543210");
    let raw = changed.to_string();
    job.preparation_sha256 = format!("{:x}", Sha256::digest(raw.as_bytes()));
    assert!(job.preparation(raw.as_bytes()).is_err());
    job.execution=NativeJobExecution::HostPinnedLive{
        guard:NativeGuardPins{source_sha:"a".repeat(40),package_version:"3.59.0".into(),native_sha256:"b".repeat(64),bwrap_sha256:"c".repeat(64)},
        sdk:NativeSdkPins{sdk_tree_sha256:"d".repeat(64),bun_sha256:"e".repeat(64),publication_sha256:"f".repeat(64)},
        live:crate::NativeLiveJob::parse(&json!({"schema":"hol-gauntlet-native-live-omp-job.v1","cell_id":crate::native_live_spec::FEATURE_AI_BASELINE,"spec_sha256":"1".repeat(64),
            "model":{"schema":"hol-gauntlet-native-live-model-pins.v1","provider_job_id":"2".repeat(16),"budget_digest":"3".repeat(64),"model_id":crate::native_live_model::MODEL,"max_turns":32,"token_limit":100000}})).unwrap()};
    for seconds in [180, crate::native_live_spec::PREPARATION_SECONDS, 991] {
        let mut prepared = value.clone();
        prepared["launch"]["wall_seconds"] = json!(seconds);
        let raw = prepared.to_string();
        job.preparation_sha256 = format!("{:x}", Sha256::digest(raw.as_bytes()));
        assert_eq!(
            job.preparation(raw.as_bytes()).is_ok(),
            seconds == crate::native_live_spec::PREPARATION_SECONDS
        );
    }
    let mut forbidden = readonly;
    forbidden["launch"]["wall_seconds"] = json!(crate::native_live_spec::PREPARATION_SECONDS);
    let raw = forbidden.to_string();
    job.preparation_sha256 = format!("{:x}", Sha256::digest(raw.as_bytes()));
    assert!(job.preparation(raw.as_bytes()).is_err());
}
