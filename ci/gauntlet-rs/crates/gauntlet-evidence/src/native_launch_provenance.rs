//! A versioned outside preparation plus signed Root journal bind launch pins.
//! Declaring an observer digest does not authenticate its process or admit it.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{digest, ineligible, require};
use crate::native_process_kernel::{hex, number};
use crate::payload::exact_keys;
use crate::{EvidenceError, Result};
use serde_json::{json, Value};

pub(crate) fn legacy_sdk_binding(context: &Value, sdk_pins: &Value, spec: &Value) -> Result<()> {
    let binding = &context["binding"];
    let peer = &binding["peer"];
    let identity = &peer["identity"];
    let terminal = &context["sdk_terminal"];
    let agent = &context["agent"];
    require(
        binding["schema"] == "hol-gauntlet-native-sdk-pre-import-binding.v3"
            && peer["schema"] == "hol-gauntlet-native-sdk-executable-peer.v2"
            && binding["assets"]["schema"] == "hol-gauntlet-verified-native-sdk-assets.v1"
            && binding["assets"]["pins"] == *sdk_pins
            && binding["assets"]["sdk_version"] == spec["sdk_version"]
            && peer["executable_sha256"] == sdk_pins["bun_sha256"]
            && exact_keys(
                terminal,
                &[
                    "returncode",
                    "timed_out",
                    "pid",
                    "start_ticks",
                    "status_source",
                ],
            )
            && terminal["status_source"] == "owned-podman-exec-kernel-exit.v1"
            && terminal["pid"] == identity["pid"]
            && terminal["start_ticks"] == identity["start_ticks"]
            && identity["pid"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= u32::MAX as u64)
            && identity["start_ticks"].as_u64().is_some_and(|n| n > 0)
            && identity["cgroup"] == peer["agent"]["identity"]["cgroup"]
            && identity["namespaces"] == peer["agent"]["identity"]["namespaces"]
            && peer["agent"]["container_id"] == agent["container_id"]
            && agent["schema"] == "hol-gauntlet-native-sdk-agent-owner.v1"
            && agent["inspection"]["HostConfig"]["NetworkMode"] == "none"
            && agent["inspection"]["HostConfig"]["Privileged"] == false
            && agent["inspection"]["HostConfig"]["ReadonlyRootfs"] == true,
    )?;
    sdk_startup(peer, sdk_pins, &binding["public_helpers"])?;
    crate::legacy_bash_case::legacy_sdk_status(&identity["status"])?;
    let helpers = binding["public_helpers"]["files"]
        .as_array()
        .filter(|rows| rows.len() <= 32)
        .ok_or(EvidenceError::Invalid(
            "actual readonly SDK helpers missing",
        ))?;
    let config = &context["episode_config"];
    for (name, hash) in [
        (
            "developer_omp_episode.ts",
            sha256(include_bytes!(
                "../../../../gauntlet/benchmark/developer_omp_episode.ts"
            )),
        ),
        (
            "builtin_guard_bridge.ts",
            sha256(include_bytes!(
                "../../../../gauntlet/benchmark/builtin_guard_bridge.ts"
            )),
        ),
        ("episode.json", digest(config)?),
    ] {
        let rows: Vec<_> = helpers.iter().filter(|row| row["name"] == name).collect();
        require(
            rows.len() == 1
                && rows[0]["sha256"] == hash
                && rows[0]["uid"] == 0
                && rows[0]["gid"] == 0
                && rows[0]["mode"] == 0o444
                && ["device", "inode"]
                    .iter()
                    .all(|key| rows[0][*key].as_u64().is_some_and(|n| n > 0)),
        )?;
    }
    require(
        exact_keys(
            config,
            &[
                "schema",
                "builtinToolProfile",
                "sdkRoot",
                "workspace",
                "agentDir",
                "modelId",
                "prompt",
                "deadlineSeconds",
                "maxToolCalls",
                "maxModelTokens",
                "sdkGate",
                "guardExtension",
                "startupProfile",
            ],
        ) && config["schema"] == "developer-omp-episode.v4"
            && config["builtinToolProfile"] == spec["builtin_tool_profile"]
            && config["sdkRoot"] == "/sdk/node_modules/@oh-my-pi/pi-coding-agent"
            && config["workspace"] == spec["workspace"]
            && config["agentDir"] == "/runtime/agent"
            && config["prompt"] == spec["prompt"]
            && config["deadlineSeconds"] == spec["execution_budget"]["episode_seconds"]
            && config["maxToolCalls"] == spec["tool_attempt_limit"]
            && config["maxModelTokens"] == spec["token_limit"]
            && config["sdkGate"] == "/runtime/sdk-gate/ready.sock"
            && config["guardExtension"] == "/runtime/public/builtin_guard_bridge.ts"
            && config["startupProfile"] == spec["sdk_startup_profile"],
    )
}

pub(crate) fn sdk_startup(peer: &Value, sdk_pins: &Value, public: &Value) -> Result<()> {
    const BUN: &str = "37141662ebed915a2ab89313156e455e2a1374395f5f6760d06407f49406f086";
    const CONFIG: &[u8] = b"preload = []\n";
    let value = &peer["startup"];
    let expected_argv = json!([
        "/runtime/bun",
        "--no-env-file",
        "--no-install",
        "--config=/runtime/public/bunfig.toml",
        "--cwd=/runtime/public",
        "/runtime/public/developer_omp_episode.ts",
        "/runtime/public/episode.json"
    ]);
    let expected_env = json!({"HOME":"/runtime/home","PATH":"/usr/bin:/bin","TMPDIR":"/tmp",
        "XDG_CONFIG_HOME":"/runtime/public","BUN_RUNTIME_TRANSPILER_CACHE_PATH":"0","DO_NOT_TRACK":"1","NO_COLOR":"1"});
    require(
        exact_keys(
            value,
            &[
                "schema",
                "profile",
                "bun_sha256",
                "argv",
                "cwd",
                "public_directory",
                "environment",
                "environment_sha256",
                "config",
            ],
        ) && value["schema"] == "hol-gauntlet-native-sdk-startup.v1"
            && value["profile"] == "bun-1.3.14-sealed-v1"
            && value["bun_sha256"] == BUN
            && sdk_pins["bun_sha256"] == BUN
            && peer["executable_sha256"] == BUN
            && value["argv"] == expected_argv
            && value["environment"] == expected_env
            && value["environment_sha256"] == digest(&expected_env)?
            && public["schema"] == "hol-gauntlet-native-sdk-public-helpers.v2",
    )?;
    let argv = expected_argv
        .as_array()
        .expect("source argv")
        .iter()
        .map(|v| v.as_str().expect("source arg"))
        .collect::<Vec<_>>();
    require(peer["argv_sha256"] == sha256(argv.join("\0").as_bytes()))?;
    let cwd = &value["cwd"];
    let directory = &value["public_directory"];
    let config = &value["config"];
    require(
        exact_keys(
            cwd,
            &["device", "inode", "uid", "gid", "mode", "mount_flags"],
        ) && exact_keys(directory, &["device", "inode", "uid", "gid", "mode"])
            && exact_keys(
                config,
                &[
                    "name",
                    "sha256",
                    "bytes",
                    "device",
                    "inode",
                    "uid",
                    "gid",
                    "mode",
                    "mount_flags",
                ],
            ),
    )?;
    for entry in [cwd, directory, config] {
        require(
            entry["uid"] == 0
                && entry["gid"] == 0
                && ["device", "inode"]
                    .iter()
                    .all(|k| entry[*k].as_u64().is_some_and(|n| n > 0)),
        )?;
    }
    require(
        cwd["mode"] == 0o755
            && directory["mode"] == 0o755
            && ["device", "inode", "uid", "gid", "mode"]
                .iter()
                .all(|key| cwd[*key] == directory[*key])
            && cwd["mount_flags"]
                .as_u64()
                .is_some_and(|flags| flags & 1 == 1)
            && config["mount_flags"]
                .as_u64()
                .is_some_and(|flags| flags & 1 == 1)
            && config["mode"] == 0o444
            && config["name"] == "bunfig.toml"
            && config["bytes"] == CONFIG.len()
            && config["sha256"] == sha256(CONFIG),
    )?;
    let files = public["files"]
        .as_array()
        .filter(|v| v.len() <= 32)
        .ok_or(EvidenceError::Invalid("actual SDK public files missing"))?;
    let selected = files
        .iter()
        .filter(|v| v["name"] == "bunfig.toml")
        .collect::<Vec<_>>();
    require(
        selected.len() == 1
            && ["device", "inode", "uid", "gid", "mode", "bytes", "sha256"]
                .iter()
                .all(|key| selected[0][*key] == config[*key]),
    )
}

pub(crate) const PIPE_HOST_HELPERS_V5: &[&str] = &[
    "/usr/bin/systemd-run",
    "/usr/bin/systemctl",
    "/usr/bin/aa-exec",
    "/usr/bin/unshare",
    "/usr/sbin/apparmor_parser",
];

/// Closed declaration selection only. A helper pin is not proof that the helper
/// executed or that nsenter entered the outside parent's held namespace.
pub(crate) fn pipe_launch(launch: &Value) -> Result<bool> {
    let v6 = match launch["schema"].as_str() {
        Some("hol-gauntlet-cell-supervisor.v5") => false,
        Some("hol-gauntlet-cell-supervisor.v6") => true,
        _ => return Ok(false),
    };
    let helpers = launch["host_helpers"]
        .as_object()
        .ok_or(crate::EvidenceError::Invalid(
            "fixed pipe-launch helpers required",
        ))?;
    require(
        helpers.len() == PIPE_HOST_HELPERS_V5.len() + usize::from(v6)
            && launch["process_events"] == "outside-root-ptrace.v1"
            && launch["native_stdio"] == "outside-root-native-pipes.v1"
            && launch["native_runtime_sha256"]
                .as_str()
                .is_some_and(|v| hex(v, 64)),
    )?;
    for name in PIPE_HOST_HELPERS_V5
        .iter()
        .copied()
        .chain(v6.then_some("/usr/bin/nsenter"))
    {
        require(
            helpers
                .get(name)
                .and_then(Value::as_str)
                .is_some_and(|v| hex(v, 64)),
        )?;
    }
    Ok(true)
}

pub(crate) fn verify(
    preparation: &Value,
    events: &[Value],
    interpreter: &str,
    observer: &str,
    journal_bound: bool,
) -> Result<Option<Value>> {
    let launch = &preparation["launch"];
    let pins = events
        .iter()
        .enumerate()
        .filter(|(_, r)| r["kind"] == "image-interpreter-pinned")
        .collect::<Vec<_>>();
    if launch["schema"] == "hol-gauntlet-cell-supervisor.v1" {
        require(
            pins.is_empty()
                && launch.get("image_interpreter_sha256").is_none()
                && launch.get("outside_observer_sha256").is_none(),
        )?;
        return Ok(None);
    }
    pipe_launch(launch)?;
    require(
        matches!(
            launch["schema"].as_str(),
            Some(
                "hol-gauntlet-cell-supervisor.v2"
                    | "hol-gauntlet-cell-supervisor.v3"
                    | "hol-gauntlet-cell-supervisor.v4"
                    | "hol-gauntlet-cell-supervisor.v5"
                    | "hol-gauntlet-cell-supervisor.v6"
            )
        ) && (launch["schema"] != "hol-gauntlet-cell-supervisor.v3"
            || launch["process_events"] == "outside-root-ptrace.v1")
            && (launch["schema"] != "hol-gauntlet-cell-supervisor.v4"
                || (launch["process_events"] == "outside-root-ptrace.v2"
                    && launch["native_stdio"] == "outside-root-native-stdio.v1"
                    && hex(
                        crate::native_diagnostic_artifacts::text(launch, "native_runtime_sha256")?,
                        64,
                    )))
            && journal_bound
            && hex(interpreter, 64)
            && hex(observer, 64)
            && launch["image_interpreter_sha256"] == interpreter
            && launch["outside_observer_sha256"] == observer
            && pins.len() == 1
            && pins[0].0 == 1
            && events[0]["kind"] == "prepared",
    )?;
    let pin = &pins[0].1["data"];
    ineligible(pin)?;
    require(
        pin.as_object().is_some_and(|v| v.len() == 15)
            && pin["schema"] == "hol-gauntlet-image-interpreter-pin.v1"
            && pin["path"] == "/usr/bin/python3.12"
            && pin["sha256"] == interpreter
            && pin["outside_observer_declared_sha256"] == observer
            && pin["uid"].as_u64() == Some(0)
            && pin["gid"].as_u64() == Some(0)
            && pin["mode"].as_u64() == Some(0o755)
            && pin["links"].as_u64() == Some(1)
            && pin["verified_before_product_launch"] == true
            && pin["bytes"]
                .as_u64()
                .is_some_and(|n| (64..=16 * 1024 * 1024).contains(&n)),
    )?;
    number(&pin["device"])?;
    number(&pin["inode"])?;
    Ok(Some(
        json!({"schema":"hol-gauntlet-native-launch-provenance.v1","interpreter_prelaunch_pinned":true,
        "interpreter_sha256":interpreter,"image_interpreter_generation":pin,"outside_observer_prelaunch_declared":true,
        "outside_observer_sha256":observer,"observer_execution_authenticated":false,"outside_signing_key_admitted":false,
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Vec<Value>) {
        let prep = json!({"launch":{"schema":"hol-gauntlet-cell-supervisor.v2","image_interpreter_sha256":"a".repeat(64),"outside_observer_sha256":"b".repeat(64)}});
        let pin = json!({"schema":"hol-gauntlet-image-interpreter-pin.v1","path":"/usr/bin/python3.12","sha256":"a".repeat(64),
            "bytes":1024,"device":2,"inode":3,"uid":0,"gid":0,"mode":493,"links":1,"verified_before_product_launch":true,
            "outside_observer_declared_sha256":"b".repeat(64),"execution_eligible":false,"guard_causality_verified":false,"model_requests":0});
        (
            prep,
            vec![
                json!({"kind":"prepared"}),
                json!({"kind":"image-interpreter-pinned","data":pin}),
                json!({"kind":"before-cell-gate"}),
            ],
        )
    }
    fn read(prep: &Value, events: &[Value], bound: bool) -> Result<Option<Value>> {
        verify(prep, events, &"a".repeat(64), &"b".repeat(64), bound)
    }
    #[test]
    fn legacy_report_cannot_gain_prelaunch_credit_from_an_invented_event() {
        let legacy = json!({"launch":{"schema":"hol-gauntlet-cell-supervisor.v1"}});
        assert_eq!(read(&legacy, &[], false).unwrap(), None);
        let (prep, events) = fixture();
        assert!(read(&legacy, &events, true).is_err());
        assert!(read(&prep, &events, false).is_err());
        let value = read(&prep, &events, true).unwrap().unwrap();
        assert_eq!(value["interpreter_prelaunch_pinned"], true);
        assert_eq!(value["observer_execution_authenticated"], false);
        assert_eq!(value["execution_eligible"], false);
    }
    #[test]
    fn late_duplicate_wrong_pin_and_changed_physical_generation_refuse() {
        let (prep, events) = fixture();
        let mut late = events.clone();
        late.swap(1, 2);
        assert!(read(&prep, &late, true).is_err());
        let mut duplicate = events.clone();
        duplicate.push(events[1].clone());
        assert!(read(&prep, &duplicate, true).is_err());
        for (field, value) in [
            ("sha256", json!("c".repeat(64))),
            ("outside_observer_declared_sha256", json!("c".repeat(64))),
            ("path", json!("/tmp/python")),
            ("uid", json!(10004)),
            ("mode", json!(0o777)),
            ("links", json!(2)),
            ("inode", json!(true)),
            ("verified_before_product_launch", json!(false)),
            ("execution_eligible", json!(true)),
        ] {
            let mut changed = events.clone();
            changed[1]["data"][field] = value;
            assert!(read(&prep, &changed, true).is_err(), "{field}");
        }
        let mut changed = prep;
        changed["launch"]["outside_observer_sha256"] = json!("c".repeat(64));
        assert!(read(&changed, &events, true).is_err());
    }

    #[test]
    fn v3_retains_prelaunch_pins_and_cannot_select_another_recorder() {
        let (mut prep, events) = fixture();
        prep["launch"]["schema"] = json!("hol-gauntlet-cell-supervisor.v3");
        assert!(read(&prep, &events, true).is_err());
        prep["launch"]["process_events"] = json!("outside-root-ptrace.v1");
        assert!(read(&prep, &events, true).unwrap().is_some());
        assert!(read(&prep, &events, false).is_err());
        prep["launch"]["process_events"] = json!("poll");
        assert!(read(&prep, &events, true).is_err());
    }

    #[test]
    fn v5_requires_pipe_mode_v1_recorder_and_actual_native_pin() {
        let (mut prep, events) = fixture();
        prep["launch"] = json!({"schema":"hol-gauntlet-cell-supervisor.v5","process_events":"outside-root-ptrace.v1",
            "native_stdio":"outside-root-native-pipes.v1","native_runtime_sha256":"c".repeat(64),
            "image_interpreter_sha256":"a".repeat(64),"outside_observer_sha256":"b".repeat(64),
            "host_helpers":PIPE_HOST_HELPERS_V5.iter().map(|name|((*name).to_owned(),json!("d".repeat(64)))).collect::<serde_json::Map<_,_>>()});
        assert!(read(&prep, &events, true).unwrap().is_some());
        for (key, value) in [
            ("process_events", json!("outside-root-ptrace.v2")),
            ("native_stdio", json!("outside-root-native-stdio.v1")),
            ("native_runtime_sha256", json!(false)),
        ] {
            let mut changed = prep.clone();
            changed["launch"][key] = value;
            assert!(read(&changed, &events, true).is_err(), "{key}");
        }
    }

    #[test]
    fn v6_requires_nsenter_without_broadening_the_v5_helper_or_transport_contract() {
        let (mut prep, events) = fixture();
        let helpers = PIPE_HOST_HELPERS_V5
            .iter()
            .map(|name| ((*name).to_owned(), json!("d".repeat(64))))
            .collect::<serde_json::Map<_, _>>();
        prep["launch"] = json!({"schema":"hol-gauntlet-cell-supervisor.v5","process_events":"outside-root-ptrace.v1",
            "native_stdio":"outside-root-native-pipes.v1","native_runtime_sha256":"c".repeat(64),
            "image_interpreter_sha256":"a".repeat(64),"outside_observer_sha256":"b".repeat(64),"host_helpers":helpers});
        assert!(read(&prep, &events, true).unwrap().is_some());
        prep["launch"]["host_helpers"]["/usr/bin/nsenter"] = json!("e".repeat(64));
        assert!(read(&prep, &events, true).is_err());
        prep["launch"]["schema"] = json!("hol-gauntlet-cell-supervisor.v6");
        let result = read(&prep, &events, true).unwrap().unwrap();
        assert_eq!(result["observer_execution_authenticated"], false);
        assert_eq!(result["execution_eligible"], false);
        assert!(read(&prep, &events, false).is_err());
        for name in PIPE_HOST_HELPERS_V5
            .iter()
            .copied()
            .chain(["/usr/bin/nsenter"])
        {
            let mut missing = prep.clone();
            missing["launch"]["host_helpers"]
                .as_object_mut()
                .unwrap()
                .remove(name);
            assert!(read(&missing, &events, true).is_err(), "{name}");
        }
        for (pointer, value) in [
            ("/launch/process_events", json!("outside-root-ptrace.v2")),
            (
                "/launch/native_stdio",
                json!("outside-root-native-stdio.v1"),
            ),
            ("/launch/native_runtime_sha256", json!(false)),
            ("/launch/schema", json!("hol-gauntlet-cell-supervisor.v7")),
        ] {
            let mut changed = prep.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(read(&changed, &events, true).is_err(), "{pointer}");
        }
        for value in [json!(false), json!("not-a-sha256"), json!("E".repeat(64))] {
            let mut changed = prep.clone();
            changed["launch"]["host_helpers"]["/usr/bin/nsenter"] = value;
            assert!(read(&changed, &events, true).is_err());
        }
        let mut changed = prep.clone();
        changed["launch"]["host_helpers"]["/bin/nsenter"] =
            changed["launch"]["host_helpers"]["/usr/bin/nsenter"].take();
        changed["launch"]["host_helpers"]
            .as_object_mut()
            .unwrap()
            .remove("/usr/bin/nsenter");
        assert!(read(&changed, &events, true).is_err());
        prep["launch"]["host_helpers"]["/usr/bin/extra"] = json!("e".repeat(64));
        assert!(read(&prep, &events, true).is_err());
    }
}
